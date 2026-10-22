# Built in the cloud by `az acr build` (cloud.sh agent): no Docker needed on your laptop.
# Microsoft: the platform needs linux/amd64 images and the container serves on port 8088.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --pre -r requirements.txt
COPY main.py policy.py ./
EXPOSE 8088
CMD ["python", "main.py"]
