FROM quay.io/dexidp/dex

COPY config.yaml .

COPY themes .

EXPOSE 5556

ENTRYPOINT ["dex","serve","config.yaml"]
