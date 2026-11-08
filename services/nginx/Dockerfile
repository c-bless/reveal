
FROM nginx:1.31.8

RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d

RUN mkdir /ssl/

COPY /ssl /ssl/
COPY /static /app/static
