FROM nginxinc/nginx-unprivileged:1.27-alpine
ENV BACKEND_URL=http://rca-backend:8000
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY index.html style.css app.js /usr/share/nginx/html/
EXPOSE 8080
