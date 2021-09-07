FROM nginx

COPY ./nginx.conf /etc/nginx/nginx.conf

COPY ./index.html /usr/share/nginx/html/index.html

# nginx image by default runs with daemon off
# Turn daemon off to avoid forking
# CMD ["nginx", "-g", "daemon off;"]
