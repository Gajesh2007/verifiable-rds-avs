# Contributing to Verifiable RDS AVS

We love your input! We want to make contributing to Verifiable RDS AVS as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

### Pull Requests

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

### Development Workflow

1. Pick an issue to work on or create a new one
2. Create a feature branch from `main`
3. Make your changes
4. Run tests locally
5. Push your branch and create a pull request
6. Wait for review and address any comments

## Code Style

For Rust code, we follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/README.html) and use `rustfmt` to format code.

For Solidity code, we follow the [Solidity Style Guide](https://docs.soliditylang.org/en/latest/style-guide.html) and use `solhint` for linting.

For TypeScript code, we use ESLint and Prettier with standard configurations.

## Testing

We require all code to be thoroughly tested. All pull requests should include appropriate tests for new features or bug fixes.

- For Rust code, use `cargo test`
- For Solidity code, use Hardhat or Truffle tests
- For TypeScript code, use Jest

## Security Considerations

Security is a top priority for this project. All code must adhere to secure coding practices:

1. All cryptographic operations must use domain separation
2. Transaction boundary protection must be implemented
3. Resource protection against DoS attacks must be considered
4. Follow the principle of least privilege

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.

## References

This document was adapted from the open-source contribution guidelines templates. 