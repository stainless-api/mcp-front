docker container rm -f mcp-front
docker run -p 8080:8080 \
  --env-file .env \
  -v "$HOME/.config/gcloud/application_default_credentials.json:/tmp/adc.json" \
  -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/adc.json \
  --name mcp-front \
  mcp-front:latest
