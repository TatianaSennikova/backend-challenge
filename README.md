## Prerequisites
Python3, pip3, sqlite3

## Install
Activate a virtual environment (recommended) and execute:

`pip install -r requirements.txt`

## Run the tests
In project root directory execute

`pytest -v`

## Run local server
In project root directory execute

```
export FLASK_ENV=development
```

`FLASK_ENV=development` is needed in order to receive a confirmation link in the logs.

Then execute

`flask run`

# Vimcar Coding Challenge: Backend

Welcome to the Vimcar Coding Challenge! We would like to see how you think and solve problems. This is an experiment to see how you design applications and write code. Feel free to use frameworks or libraries of your choice to achieve the goal.

When you've finished your work, either upload your challenge to GitHub and let us know, or send the source code directly via email.


## Your Task
Most websites provide the possibility to create a personal user account to gain access to additional features or personalized content.
 
The challenge is to create a simple (preferably [Flask](http://flask.pocoo.org/) based) application which provides an RESTful API with the following features:

#### Sign Up
- the user can create a new account with a given email address and password
- the user receives an confirmation email 
- for account activation, the user has to click an activation link, provided in the email

#### Authentication
- the user can log in to the system with the chosen email address and password


#### Authorization
- the user can access a protected resource only if they have been authenticated
- anonymous access to these resources may not be possible


## What we expect
- a working application that exposes a RESTful API, which allows to sign up, sign in and only then to access a protected resource 
- clean, well structured code that follows best practices
- document the code in the way you think it fits best
- the user accounts should be stored in some kind of persistence

## Voluntary Additions
- unit and/or functional tests
 - an explanation of how you decided what tests to write
- a production-ready deployment configuration (means: not using the Flask development server)
- Docker setup (to provision the whole stack via `docker-compose up`)
 - a `Dockerfile` to build the Docker image
 - a `docker-compose.yml` to describe the full stack
- explanations, why you chose a specific implementation or pattern, framework or library compared to other options (e.g. for cross-request authentication) 


## Not expected
- it's not required to connect the API to a frontend or website, to provide sign up or login forms, etc.
- the email does not need to be send over the wire. Using e.g. [Mailhog](https://github.com/mailhog/MailHog) or just logging the email body is totally fine, as long as it's possible to receive and use the activation link
