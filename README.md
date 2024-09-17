# FastAPI Zero Trust Authorization Framework

This FastAPI application demonstrates a Zero Trust Authorization Framework for cloud-native applications. It includes JWT authentication, custom role-based access control (RBAC), mutual TLS (mTLS) for secure communication, and real-time updates using WebSockets.

## Features

- **JWT Authentication**: Secure access using JSON Web Tokens.
- **Custom RBAC**: Role-based access control for protected routes.
- **Mutual TLS (mTLS)**: Secure communication using client and CA certificates.
- **WebSocket**: Real-time policy updates and event handling.

## Setup

### Prerequisites

- Python 3.8+
- Pip

### Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/pravintargaryen/zerotrust.git
   cd your-repository
   ```

2. **Create and activate a virtual environment:**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install Dependencies**

```bash
pip install -r requirements.txt

```

4. **Configuration**

1. Certificates: Replace client.pem, client-key.pem, and ca.pem with your actual certificate files. Ensure they are in the project directory.

1. Update SECRET_KEY: In main.py, replace your-secret-key with a strong, unique key.

1. **Running the Application**

```bash
uvicorn main:app --reload

```

5. **Testing with Postman**
   Obtain a JWT Token:

```bash
Method: POST
URL: http://localhost:8000/token
Body: x-www-form-urlencoded
username: user1
password: password1
Access Protected Routes:

Method: GET
URL: http://localhost:8000/secure-data
Headers:
Authorization: Bearer your-jwt-token
Test mTLS:

Configure client certificates in Postman:

CRT File: client.pem
KEY File: client-key.pem
CA File: ca.pem
Method: GET

URL: http://localhost:8000/mTLS-endpoint

Test WebSocket:

Use a WebSocket client tool like wscat or a browser extension to connect to:
WebSocket URL: ws://localhost:8000/ws/policy-updates
```
