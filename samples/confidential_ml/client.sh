HOST=localhost
PORT=8000
IMAGE_FILE="${1}" 

echo "\n"
curl -F "image=@${IMAGE_FILE}" ${HOST}:${PORT}/evaluate
