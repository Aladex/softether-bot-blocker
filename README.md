# softether-bot-blocker
Parse logs from softether and block addresses

# How to install

Clone code to your server

`git clone https://github.com/Aladex/softether-bot-blocker.git`

Go to the blocker folder

`cd softether-bot-blocker`

Create folder for binary

`mkdir -p /opt/blockspam`

Copy binary and config to install folder

```
cp release/blockSpam /opt/blockspam/.
cp release/config.yml /opt/blockspam/.
```

Copy service file to systemd folder

`cp release/blockspam.service /etc/systemd/system/.`

Reload services

`systemctl daemon-reload`

Start service

`systemctl start blockspam`