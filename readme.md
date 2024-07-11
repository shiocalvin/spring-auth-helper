# AuthenticateHelper README

This package, `com.medjay.authenticatehelper`, provides a robust authentication helper for a Spring Boot application. It includes JWT-based authentication, Redis integration for storing permissions, and a custom security configuration.

## Table of Contents
1. [Setup](#setup)
2. [Components](#components)
3. [Configuration](#configuration)
4. [Usage](#usage)
5. [Error Handling](#error-handling)

## Setup

### Prerequisites
- Java 11+
- Spring Boot
- Redis Server

### Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/your-repo/authenticatehelper.git
    ```

2. Navigate to the project directory:
    ```sh
    cd authenticatehelper
    ```

3. Build the project:
    ```sh
    mvn clean install
    ```

4. Run the Spring Boot application:
    ```sh
    mvn spring-boot:run
    ```

## Components

### Main Application
- **AuthenticateHelperApplication**: The entry point of the Spring Boot application.

### Controllers
- **AuthTestController**: A simple controller to test the authentication process.

### Security Configuration
- **SecurityConfiguration**: Configures the Spring Security settings, including public URLs and JWT filter integration.

### Filters
- **JwtFilter**: Custom filter to process JWT tokens in incoming requests.

### Services
- **JwtService**: Handles JWT token operations like extraction and validation.
- **RedisService**: Manages Redis operations, particularly fetching user permissions.

### Authentication
- **UserAuthenticationToken**: Custom implementation of `AbstractAuthenticationToken` for security context management.

### Error Handling
- **AuthErrorCodes**: Enum defining various authentication error codes and messages.
- **AuthErrorResponse**: Record for structuring authentication error responses.
- **DefaultAuthException**: Custom exception for authentication errors.

## Configuration

### Application Properties
Ensure the following properties are set in `application.properties`:

```properties
# JWT secret key
authentication.secret-key=your-secret-key

# Header acronym for JWT
authentication.header-acronym=Bearer 

# Public URLs that do not require authentication
authentication.open-urls=/public/**

# Redis configuration
authentication.redis.host-name=localhost
authentication.redis.port=6379

```
## Usage
I made this to ease my pain in spinning up new microservices in our env that will have token authentication and get 
permission from a redis cache.

You can simply copy all other classes other than the main class or simply package this and use it as a dependency in 
your application.