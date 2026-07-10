# Contributing to Trels

Thank you for your interest in contributing to Trels! We welcome all contributions from bug fixes to feature additions, documentation improvements, and feedback.

## How to Contribute

### 1. Reporting Bugs
- Search existing issues to see if the bug has already been reported.
- If not, open a new issue. Describe the issue clearly, including steps to reproduce, the OS you are using, and the expected vs. actual behavior.

### 2. Suggesting Enhancements
- Open an issue explaining the proposed feature and why it would be useful for the project.

### 3. Pull Requests
- Fork the repository and create your branch from `master`.
- Keep your changes focused. If you want to fix multiple unrelated issues, submit separate pull requests.
- Ensure your code builds successfully:
  - On Windows: run `build/build.bat`
  - On Linux: run `build/build.sh`
- Run the tests to ensure no regressions are introduced:
  ```bash
  cd backend
  go test -v
  ```
- Make sure to format your Go code: `go fmt ./...`.
- Submit the pull request and reference any related issues.

## Code Style

- **Go**: Follow standard Go practices and styling (`gofmt`).
- **Frontend**: Keep the code clean, fast, and structured. Stick to Vanilla CSS and Vanilla JavaScript (avoid adding framework dependencies).
- **Commit Messages**: Write clear, descriptive commit messages (e.g. `Fix: resolve nil pointer in proxy handler`).

## Community Guidelines

Please note that this project is released with a [Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project, you agree to abide by its terms.
