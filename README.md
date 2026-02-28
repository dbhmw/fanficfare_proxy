# Installation

## Step 1: Generate Certificates

Run the certificate generation script in your cloned directory:
```bash
python generate_certs.py
```
This creates three folders:
- `__client_certs`
- `__server_certs`
- `__ca`

## Step 2: Set Up the Server

Choose your preferred method below.

### Option A: Python

1. Update `config.ini` with the actual paths to your files:
```ini
   chrome = ./chromium/chrome
   cert = ./__server_certs/server_cert.pem
   key = ./__server_certs/server_key.pem
   cacert = ./__server_certs/local_ca_cert.pem
```
  Replace the paths above with the actual locations on your system.

2. Create a Python virtual environment:
```bash
   python -m venv ./fff_proxy
```

3. Activate the environment:
```bash
   source ./fff_proxy/bin/activate
```

4. Install required packages:
```bash
   pip install -r requirements.txt
```

5. Start the server:
```bash
   python driverless.py
```

### Option B: Docker

1. Build and start the services:
```bash
   docker-compose up --build
```

The server should be running once this command completes.

# Usage

### Fanficfare Config

```ini
[defaults]
driverless_proxy_cacert:./__client_certs/local_ca_cert.pem
driverless_proxy_cert:./__client_certs/client_cert.pem
driverless_proxy_key:./__client_certs/client_key.pem
[example.com]
use_driverless_proxy: true
```
Again, replace the paths above with the actual locations on your system.

### Running after install initial install

#### Option A
Activate the virtual env and run the python script
```bash
   source ./fff_proxy/bin/activate
   python driverless.py
```

#### Option B
Just run
```bash
   docker-compose up
```
