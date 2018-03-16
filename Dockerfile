FROM scratch
ADD webhook /webhook
ENTRYPOINT ["/webhook"]
