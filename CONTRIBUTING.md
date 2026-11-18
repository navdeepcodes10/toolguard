# Contributing to ToolGuard

Thank you for your interest in improving ToolGuard! We welcome contributions to make AI coding agents safer for the entire developer community.

---

## 🛠️ Local Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/navdeepcodes10/toolguard.git
   cd toolguard
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Build the TypeScript source:**
   ```bash
   npm run build
   ```

4. **Run the test suite:**
   ```bash
   npm test
   ```

---

## 🛡️ Adding a New Security Rule

All core security checks reside in `src/core/`.

When contributing a new rule:
1. Identify the threat category (e.g., destructive command, secret leak, SSRF bypass).
2. Implement your logic in `src/core/ruleEngine.ts` or as a new modular guard under `src/core/`.
3. Ensure normalized tokens are used to prevent quote-wrapping or argument-splitting bypasses.
4. Add comprehensive unit tests in `src/tests/securityEngine.test.ts`.

---

## 🧪 Test Requirements

Every pull request must pass the test suite:
```bash
npm test
```

Guidelines:
- Include tests for both positive cases (harmful commands get blocked) and negative cases (safe commands remain unblocked).
- Ensure execution time remains under 100ms.
- Avoid introducing heavy third-party runtime dependencies.

---

## 📋 Pull Request Process

1. Create a feature branch: `git checkout -b feature/your-rule-name`.
2. Commit your changes with clear, descriptive commit messages.
3. Push to your branch and submit a Pull Request against `main`.
4. Automated CI will run linting, TypeScript compilation, and test execution.
