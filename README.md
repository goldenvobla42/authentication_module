# authentication_module
This project provides functionality to create and validate authentication tokens, supporting role-based access control. 

It includes two authentication modules: one for symmetric key encryption (authmodule.py) and another for asymmetric key encryption (authmodule_asym.py). 

The application also contains unit tests (unittests.py) for the authentication modules. 

A web application using Flask implemented for demo token-based authentication. 
The Flask app (app.py) provides several token management and authentication routes, including creating tokens, validating tokens, and accessing an admin page with role-based access control. 
Templates are provided for the user interface, including pages for token creation, token validation, and an admin page.

The project includes a Dockerfile for containerization.


# Installation

To run the application, follow these steps:

1. Clone this repository:
```bash
git clone https://github.com/goldenvobla42/authentication_module.git
```
2. Navigate to the project directory:
```bash
cd authentication_module
```
3. If using Docker, build and run the Docker image:
```bash
docker build -t app .
docker run -p 8080:8080 app
```
If not, install the dependencies and run the Flask application:
```bash
pip install --no-cache-dir -r requirements.txt
export SECRET_KEY="your_secret_key_value"
flask run
```
4. Access the application in the web browser at http://127.0.0.1:8080 (if using Docker) or http://127.0.0.1:5000 (if not using Docker).

# Web application 
In web application you can:
- Open start page  http://127.0.0.1:8080/ and choose the option
- Create a token: http://127.0.0.1:8080/create
Here you can create token with user_id and roles. Also, you can add this token to localstorage. And you can try access to admin page. 
- Validate a token: http://127.0.0.1:8080/validate
- Access the admin page (requires admin role in token): http://127.0.0.1:8080/admin

Success paths are: 
- create token -> copy it -> validate token
- create token with admin role -> go to admin page
- create token withhout admin role -> go to admin page and see the error


# Running Tests

To run the unit tests, use the following command:

```bash
python unittests.py
```

# Implementation with asymmetric signing

Implementation with asymmetric signing is not integrated to web application (yet). 
