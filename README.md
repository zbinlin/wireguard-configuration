
## Server side

Requirements:

* socat
* nmap
* iptables/ip6tables

```sh
# socat EXEC:./server.sh,pty,rawer TCP-LISTEN:12345,bind=192.168.128.1,fork,reuseaddr
./start-server.sh
# or
sudo ./start-server.sh
```

## Client side

```sh
export ENDPOINT=<...>
export REMOTE_HOSTNAME=192.168.128.1
export REMOTE_PORT=12345
./start-client.sh
```

## Alt

Wireguard over Websocket (*TODO*)

1. Install `websocat`

```sh
cargo install --features=ssl websocat
```

2.

If use nginx as websocat proxy, first configure nginx.

Server:

```sh
websocat --udp-reuseaddr -E -b --restrict-uri / ws-listen:172.17.0.1:8443 udp:127.0.0.1:8443
```

Or direct use websocat, generate pkcs12 cert:

```sh
openssl pkcs12 -export -out cert.pkcs12 -inkey key.pem -in cert.pem
```

then

```sh
websocat --udp-reuseaddr -E -b --restrict-uri / --pkcs12-der ./cert.pkcs12 --pkcs12-passwd <PASSWORD> ws-listen:172.17.0.1:443 udp:127.0.0.1:8443
```

Client:

```sh
websocat -E --ping-interval 10 --ping-timeout 30 -b udp-listen:127.0.0.1:8443 autoreconnect:wss://<SERVER>
```
or
```sh
websocat -E --ping-interval 10 --ping-timeout 30 --ws-c-uri ws://<WE_ENDPOINT> --tls-domain <WS_DOMAIN> -b udp-listen:127.0.0.1:8443 autoreconnect:ws-c:tls-connect:tcp:<IP>:<PORT>
```

and configure wireguard endpoint as `127.0.0.1:8443`.

**NOTE:** The websocket server ip must be bypass wireguard.
