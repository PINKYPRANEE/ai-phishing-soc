# Use an official, lightweight Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the required packages safely
RUN pip install --no-cache-dir -r requirements.txt

# Copy all the rest of your project files (app.py, models, CSV, etc.) into the container
COPY . .

# Expose the port Streamlit uses so we can view the dashboard
EXPOSE 8501

# Command to run the Streamlit application when the container starts
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]