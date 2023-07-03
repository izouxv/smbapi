docker run -d --network=host my-container:latest
docker run -it --network=host --rm --name testubuntu ubuntu:14.04
docker run -it --rm --name testubuntu --network=host ubuntu:14.04
apt install smbclient

smbclient -L 127.0.0.1:445 -U name%pwd
smbclient -L 192.168.1.2 -m smb2
smbclient -L 192.168.1.2 -m smb2 -U name --password pwd
