# Zero Trust Network Implementation

The project aims to develop an implementation of zero trust architecture based on zero trust principles. It focuses on enhancing security by ensuring that no one, whether inside or outside the organization, is trusted by default. Instead, verification is required from anyone trying to access resources on the network.

## Project Overview

The implementation will rely on the following components:

- **Trust Engine**: A trust engine will be implemented to calculate the trust scores of different subjects accessing various resources. It will assess user behavior, device health, and other factors to determine trust levels.

- **Policy Engine**: A policy engine component will enforce access control policies based on trust scores and other parameters. It ensures that users and devices can only access resources for which they have the necessary permissions.

- **Access Proxy**: An access proxy will act as an intermediary between users/devices and resources. It will enforce policies, authenticate users, and log access attempts.

## Technologies Used

The project will utilize various technologies, including:

- Trust Engine: Python, Machine Learning Algorithms, Markov chains
- Policy Engine: Python
- Access Proxy: Nginx, OAuth, Flask framework

## Getting Started

To get started with the project, follow these steps:

1. Clone the repository: `git clone https://github.com/LeoneOdinga/ZeroTrustArchitecture.git`
2. Install dependencies and set up the required environment.

## Contribution Guidelines

Contributions are welcome! Please follow these guidelines when contributing to the project:

- Fork the repository and create a new branch for your feature/bugfix.
- Ensure your code follows the project's coding standards.
- Submit a pull request, clearly describing the changes you made.

## License
