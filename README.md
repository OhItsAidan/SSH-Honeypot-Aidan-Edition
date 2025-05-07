# SSH-Honeypot-Project
This is my SSH Honeypot for CMP509 Ethical Hacking

## 📁 File Structure
```
ssh_honeypot_project/
├── Dockerfile
├── README.md
├── requirements.txt
├── server.key
├── server.pub
├── ssh_honeypot.log
├── src/
| └── ssh_honeypot.py
```
## Lets begin!
Start by navigating to the folder within your chosen shell, ideally PowerShell if on Windows, or the standard Linux Terminal if on Linux.
### 1. Build the Docker Image

```bash
docker build -t ssh_honeypot .
```

### 2. Run the Docker Container
```bash
docker run -d -p 2222:2222 --name ssh_honeypot ssh-honeypot
```

### 3. Once running you should be able to log in with any credentials
```
ssh -i server.key -p 2222 testuser@127.0.0.1
testuser@127.0.0.1's password: 
```
### 4. Stopping and Restarting
If you exit the honeypot and want to return to it, this is necessary as the Docker container will still be attached to the port. 
Stopping the container:
```bash
docker stop <container_id>
```
Remove the container:
```bash
docker rm <container_id>
```
Restart after building:
```bash
docker build -t ssh-honeypot .
docker run -d -p 2222:2222 --name ssh_honeypot ssh-honeypot
```
### 5. Commands
Use the following for a list of commands available within the honeypot, each commands entered is logged in the log file.
```bash
help
```
## 🔐 SSH Key Permissions
You need to ensure the server key has the correct permissions, if the key is refused, use this command:
```bash
chmod 600 server.key
```

## 📄 Log Output
A big part of this project is to capture the activity within the honeypot, the results are recorded into /app/ssh_honeypot.log inside the container. You can view them with this command:
```bash
docker exec -it ssh_honeypot cat /app/ssh_honeypot.log
```
If you want to copy the logs to your host machine, run:
```bash
docker cp ssh_honeypot:/app/ssh_honeypot.log ./ssh_honeypot.log
```

### ⚠️ Known Issues
- If you end up rebuilding often, you may need to remove the old container.
- If a port is reported as "already allocated" look at step 3.
- Always run Docker with sudo if your user does not have the necessary permissions

### 📚 Usage
This honeypot is for educational and research purposes only. Please use responsibly.

If any issues, please do not hesitate to reach me on my email - a1dankhd@gmail.com








