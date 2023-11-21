# SpyderByte

An intelligent web-proxy that monitors API requests of a web application and detects API security vulnerabilities automatically.

The tool requires no security testing experience and was designed for developers who want to secure their applications but don't have a great knowledge of application security or API security.

The tool detects several OWASP Top 10 and OWASP API Top 10 vulnerabilities, including:

- **Server-Side Request Forgery (SSRF)**
	- Under: OWASP API Top 10 Release Candidates 2023, OWASP top 10 2021

- **Faulty JWT Signature - "None" attack**
	- Under: OWASP top 10 2021

- **Insecure Direct Object Referencing (IDOR)**
	- Under: OWASP API top 10 2019, OWASP top 10 2021 
	

Detected vulnerabilities are reported on a dashboard that shows:
- An explanation of the vulnerability
- The vulnerable endpoint
- The content of the vulnerable request
- The reasoning behind the detection (detection logic)
