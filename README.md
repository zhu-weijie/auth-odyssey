# Auth-Odyssey

> A Python/FastAPI project demonstrating key authentication patterns: API Keys, JWT (with refresh tokens & RBAC), and OAuth 2.0.

This project is a hands-on guide to implementing modern authentication and authorization. It was built step-by-step to demonstrate different security schemes, from simple API Keys to a complete OAuth 2.0 flow, all backed by a persistent database and a modular application structure.

## ✨ Features

-   **API Key Authentication**: Secure service-to-service endpoints with a simple, validated API key.
-   **JWT-Based Authentication**: Full username/password login flow using signed JSON Web Tokens.
-   **Secure Password Storage**: Uses `passlib` with `bcrypt` for industry-standard password hashing.
-   **Refresh Tokens**: Long-lived refresh tokens allow clients to get new access tokens without forcing users to re-authenticate, featuring token rotation for enhanced security.
-   **Role-Based Access Control (RBAC)**: Protects certain endpoints by requiring specific user roles (e.g., "admin") embedded in the JWT.
-   **OAuth 2.0 Integration**: Allows users to register and log in via a third-party provider (GitHub).
-   **Persistent Database**: Uses **SQLModel** (Pydantic + SQLAlchemy) with a SQLite backend to store user data.
-   **Modular Project Structure**: The code is organized into routers, services, and models for better scalability and maintainability.
-   **Minimalist Frontend Client**: A vanilla JavaScript single-page application demonstrates how to interact with the API, handle tokens, and make authenticated requests.

## 🚀 Getting Started

Follow these instructions to get the project running on your local machine.

### Prerequisites

-   Python 3.12+
-   A GitHub account (to create an OAuth application for testing the OAuth 2.0 flow)

### Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/auth-odyssey.git
    cd auth-odyssey
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    # On Windows, use: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up your environment variables:**
    Create a `.env` file in the project root. You can copy the example below.
    ```env
    # .env

    # Used for simple X-API-Key authentication
    API_KEY="my-super-secret-api-key"

    # Used for signing short-lived JWT access tokens (generate with `openssl rand -hex 32`)
    JWT_SECRET_KEY="your_32_byte_hex_secret_for_jwt"

    # Used for signing long-lived JWT refresh tokens (generate with `openssl rand -hex 32`)
    JWT_REFRESH_SECRET_KEY="a_different_32_byte_hex_secret_for_refresh"
    REFRESH_TOKEN_EXPIRE_DAYS=7

    # Get these from your GitHub OAuth App settings
    GITHUB_CLIENT_ID="your_github_client_id"
    GITHUB_CLIENT_SECRET="your_github_client_secret"
    ```
    *To get GitHub credentials, create a new OAuth App [here](https://github.com/settings/developers). Set the "Authorization callback URL" to `http://127.0.0.1:8000/api/auth/github/callback`.*

5.  **Run the application:**
    The application is now managed within the `app` directory. Use the following command:
    ```bash
    uvicorn app.main:app --reload
    ```

6.  **Access the client:**
    Open your web browser and navigate to **http://127.0.0.1:8000/**. You will see the frontend client, where you can test all the features.

## 🛠️ API Endpoints

The frontend client at the root URL (`/`) interacts with the following API endpoints, all prefixed with `/api`.

| Endpoint                    | Method | Authentication      | Description                                          |
| --------------------------- | ------ | ------------------- | ---------------------------------------------------- |
| `/users`                    | `POST` | None                | Register a new user with a username and password.    |
| `/token`                    | `POST` | None (Form Data)    | Log in to get an access and refresh token pair.      |
| `/token/refresh`            | `POST` | Bearer (Refresh)    | Exchange a valid refresh token for a new token pair. |
| `/users/me`                 | `GET`  | Bearer (Access)     | Get the profile of the currently authenticated user. |
| `/login/github`             | `GET`  | None                | Redirects to GitHub to start the OAuth 2.0 flow.   |
| `/auth/github/callback`     | `GET`  | None                | Callback URL for GitHub to complete the OAuth flow.  |
| `/protected`                | `GET`  | API Key             | A sample endpoint protected by a static API key.     |
| `/admin/users`              | `GET`  | Bearer (Admin Role) | Get a list of all users in the database.             |
| `/admin/promote/{username}` | `POST` | Bearer (Admin Role) | Promote a user to the 'admin' role.                  |

---

## Design Diagrams

### Class Diagram

```mermaid
classDiagram
    direction LR

    %% --- Core Application ---
    class FastAPI {
        <<Application>>
        +include_router(APIRouter)
        +mount(StaticFiles)
    }
    class APIRouter {
        <<Router>>
        +register_user(UserCreate) UserPublic
        +login_for_access_token(Form) Token
        +read_users_me(user) UserPublic
    }

    %% --- Data & DB Models ---
    class SQLModel {
        <<Base Model>>
    }
    class User {
        <<DB Table>>
        +id: int
        +username: str
        +hashed_password: str
        +role: str
    }
    class UserCreate {
        <<API Model>>
        +username: str
        +password: str
    }
    class UserPublic {
        <<API Model>>
        +id: int
        +username: str
        +role: str
    }
    class Token {
        <<API Model>>
        +access_token: str
        +refresh_token: str
    }

    %% --- Services & Logic ---
    class Auth {
        <<Service Module>>
        +verify_password(plain, hashed) bool
        +create_access_token(data) str
        +get_current_user(token) User
        +require_admin_user(user) User
    }
    class CRUD {
        <<Service Module>>
        +get_user_by_username(db, username) User
        +create_db_user(db, UserCreate) User
    }

    %% --- Configuration ---
    class Settings {
        <<pydantic_settings>>
        +API_KEY
        +JWT_SECRET_KEY
    }

    %% --- Relationships ---
    FastAPI o-- APIRouter : includes
    
    SQLModel <|-- User
    SQLModel <|-- UserCreate
    SQLModel <|-- UserPublic
    SQLModel <|-- Token
    
    APIRouter o-- Auth : "uses as dependency"
    APIRouter o-- CRUD : "uses for data"
    
    Auth ..> CRUD : "uses for user lookup"
    Auth ..> Settings : "reads secrets"
    
    CRUD o-- User : "operates on"
    
    APIRouter ..> UserCreate : "accepts as body"
    APIRouter ..> UserPublic : "returns as response"
    APIRouter ..> Token : "returns as response"

    note for APIRouter "Endpoints use Auth functions as FastAPI Dependencies."
```

### API Key Sequence Diagram

```mermaid
sequenceDiagram
    participant Client
    participant FastAPI_Backend as FastAPI Backend
    participant get_api_key as API Key Dependency
    participant read_protected_data as Endpoint Logic
    participant Settings as .env / Settings

    alt Valid API Key
        Client->>FastAPI_Backend: GET /api/protected (with X-API-Key header)

        activate FastAPI_Backend
        Note over FastAPI_Backend: Endpoint is protected, must run dependency first.
        FastAPI_Backend->>get_api_key: Execute dependency: get_api_key(key_from_header)
        
        activate get_api_key
        get_api_key->>Settings: Read SECRET_API_KEY
        Settings-->>get_api_key: Return stored API Key
        
        note right of get_api_key: Compares keys using secrets.compare_digest()
        note right of get_api_key: Comparison is True.
        
        get_api_key-->>FastAPI_Backend: Validation successful
        deactivate get_api_key

        FastAPI_Backend->>read_protected_data: Call endpoint logic now
        activate read_protected_data
        read_protected_data-->>FastAPI_Backend: Return protected data (JSON)
        deactivate read_protected_data
        
        FastAPI_Backend-->>Client: HTTP 200 OK with data
        deactivate FastAPI_Backend

    else Invalid or Missing API Key
        Client->>FastAPI_Backend: GET /api/protected (with bad/missing X-API-Key)
        
        activate FastAPI_Backend
        Note over FastAPI_Backend: Endpoint is protected, must run dependency first.
        FastAPI_Backend->>get_api_key: Execute dependency: get_api_key(...)

        activate get_api_key
        get_api_key->>Settings: Read SECRET_API_KEY
        Settings-->>get_api_key: Return stored API Key
        
        note right of get_api_key: Compares keys using secrets.compare_digest()
        note right of get_api_key: Comparison is False.
        
        get_api_key-->>FastAPI_Backend: Raise HTTPException(401 Unauthorized)
        deactivate get_api_key
        
        note over FastAPI_Backend: Request processing stops here! Endpoint logic is never called.
        
        FastAPI_Backend-->>Client: HTTP 401 Unauthorized
        deactivate FastAPI_Backend
    end
```

### JWT Sequence Diagram

```mermaid
sequenceDiagram
    participant Client
    participant Login_Endpoint as Login Endpoint (/token)
    participant Auth_Service as Auth Service
    participant CRUD_Service as CRUD Service
    participant Database
    participant JWT_Dependency as JWT Dependency (get_current_user)
    participant Protected_Endpoint as Protected Endpoint (/users/me)
    participant FastAPI_Backend as FastAPI Backend

    %% === Phase 1: User logs in to get a token ===

    Client->>FastAPI_Backend: POST /api/token (username, password)
    activate FastAPI_Backend
    FastAPI_Backend->>Login_Endpoint: Route request
    
    activate Login_Endpoint
    Login_Endpoint->>CRUD_Service: get_user_by_username(username)
    activate CRUD_Service
    CRUD_Service->>Database: SELECT * FROM user WHERE ...
    activate Database
    Database-->>CRUD_Service: Return user record (with hashed_password)
    deactivate Database
    CRUD_Service-->>Login_Endpoint: Return User object
    deactivate CRUD_Service
    
    Login_Endpoint->>Auth_Service: verify_password(plain_password, hashed_password)
    activate Auth_Service
    Note right of Auth_Service: Hashes plain pass & compares
    Auth_Service-->>Login_Endpoint: Return True
    
    Login_Endpoint->>Auth_Service: create_access_token(user_data)
    Note right of Auth_Service: Creates JWT with payload (sub, role, exp) and signs it.
    Auth_Service-->>Login_Endpoint: Return JWT string
    deactivate Auth_Service
    
    Login_Endpoint-->>FastAPI_Backend: Return {"access_token": "..."}
    deactivate Login_Endpoint
    FastAPI_Backend-->>Client: HTTP 200 OK with JWT
    deactivate FastAPI_Backend

    Note over Client: Client stores the received JWT

    %% === Phase 2: Client uses the JWT to access a protected resource ===
    
    alt Successful Access (Valid Token)
        Client->>FastAPI_Backend: GET /api/users/me (with "Authorization: Bearer <JWT>")
        activate FastAPI_Backend
        
        Note over FastAPI_Backend: Endpoint is protected, run dependency first.
        FastAPI_Backend->>JWT_Dependency: Execute get_current_user(token)
        activate JWT_Dependency
        
        Note right of JWT_Dependency: Dependency validates token signature & expiry.
        JWT_Dependency->>CRUD_Service: get_user_by_username(username_from_token)
        activate CRUD_Service
        CRUD_Service->>Database: SELECT * FROM user ...
        activate Database
        Database-->>CRUD_Service: Return user record
        deactivate Database
        CRUD_Service-->>JWT_Dependency: Return User object
        deactivate CRUD_Service
        
        JWT_Dependency-->>FastAPI_Backend: Return valid User object
        deactivate JWT_Dependency
        
        Note over FastAPI_Backend: Dependency success. Proceed to endpoint logic.
        FastAPI_Backend->>Protected_Endpoint: Call endpoint, injecting User
        activate Protected_Endpoint
        Protected_Endpoint-->>FastAPI_Backend: Return public user data (JSON)
        deactivate Protected_Endpoint
        
        FastAPI_Backend-->>Client: HTTP 200 OK with user data
        deactivate FastAPI_Backend

    else Invalid or Expired Token
        Client->>FastAPI_Backend: GET /api/users/me (with bad JWT)
        activate FastAPI_Backend

        FastAPI_Backend->>JWT_Dependency: Execute get_current_user(token)
        activate JWT_Dependency
        Note right of JWT_Dependency: Token decoding fails (bad signature or expired).
        JWT_Dependency-->>FastAPI_Backend: Raise HTTPException(401 Unauthorized)
        deactivate JWT_Dependency
        
        Note over FastAPI_Backend: Request processing stops. Endpoint is never called.
        FastAPI_Backend-->>Client: HTTP 401 Unauthorized
        deactivate FastAPI_Backend
    end
```

### OAuth Sequence Diagram

```mermaid
sequenceDiagram
    participant User's Browser
    participant Our Application Backend
    participant GitHub Authorization Server
    participant GitHub API Server
    participant Our Database

    %% === Phase 1: User initiates login and is redirected ===

    User's Browser->>Our Application Backend: GET /api/login/github
    activate Our Application Backend
    note right of Our Application Backend: Redirects to GitHub's auth URL with our client_id.
    Our Application Backend-->>User's Browser: HTTP 302 Redirect to github.com/login/oauth/authorize
    deactivate Our Application Backend

    %% === Phase 2: User authorizes the application on GitHub ===

    User's Browser->>GitHub Authorization Server: Follows redirect
    activate GitHub Authorization Server
    note over User's Browser, GitHub Authorization Server: User sees the consent screen, logs into GitHub if necessary, and clicks "Authorize".
    note right of GitHub Authorization Server: GitHub generates a temporary authorization code.
    GitHub Authorization Server-->>User's Browser: HTTP 302 Redirect to our callback URL with the code.<br/>(e.g., /api/auth/github/callback?code=xyz)
    deactivate GitHub Authorization Server

    %% === Phase 3: Backend exchanges the code for an access token ===

    User's Browser->>Our Application Backend: Follows redirect to our callback URL
    activate Our Application Backend
    note over Our Application Backend: Now the backend takes over. The browser just waits.
    Our Application Backend->>GitHub Authorization Server: POST /login/oauth/access_token (server-to-server)<br/>{ code, client_id, client_secret }
    activate GitHub Authorization Server
    note right of GitHub Authorization Server: Validates code and client credentials.
    GitHub Authorization Server-->>Our Application Backend: Return { "access_token": "gh_user_token" }
    deactivate GitHub Authorization Server

    %% === Phase 4: Backend fetches user info and creates internal session ===

    Our Application Backend->>GitHub API Server: GET /user (server-to-server)<br/>(Authorization: Bearer gh_user_token)
    activate GitHub API Server
    GitHub API Server-->>Our Application Backend: Return User Profile (JSON)
    deactivate GitHub API Server

    note right of Our Application Backend: Now, work with our own database.
    Our Application Backend->>Our Database: Find or Create user record by github_id
    activate Our Database
    Our Database-->>Our Application Backend: Return internal User object
    deactivate Our Database

    note right of Our Application Backend: Create OUR OWN internal JWT for this user.
    
    Our Application Backend-->>User's Browser: HTTP 302 Redirect to /api/dashboard?token=our_internal_jwt
    deactivate Our Application Backend
    
    User's Browser->>Our Application Backend: Follows final redirect to dashboard
    Note over User's Browser: Login is complete. Browser now has our internal JWT.
```
