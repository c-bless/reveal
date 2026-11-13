
FROM nginx:1.31.8

RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d

# Run as the unprivileged user "nginx" (uid 101) of the base image:
# - no "user" directive (only possible for a master process running as root)
# - pid file in /tmp (/run is writable only for root)
# - cache / temp directories (e.g. buffered uploads) writable for nginx
# The listen ports are unprivileged (8080, 4443, 8443), docker-compose.yml maps them to 80, 443 and 8443.
RUN sed -i -e '/^user /d' -e 's|^pid .*|pid        /tmp/nginx.pid;|' /etc/nginx/nginx.conf \
    && chown -R nginx:nginx /var/cache/nginx

# certificates and private keys: owned by root, readable for the group nginx only
COPY --chown=root:nginx /ssl /ssl/
RUN chmod 750 /ssl && chmod 640 /ssl/*

COPY /static /app/static

EXPOSE 8080 4443 8443

USER nginx
