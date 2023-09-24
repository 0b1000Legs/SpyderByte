from .AttackClassType import AttackClassType

ATTACK_CLASS_DETAILS = {
    AttackClassType.IDOR: {
        "name": "Insecure Direct Object References",
        "acronym": "IDOR",
        "description": "There is a vulnerability in enforcing access control measures, where certain user assets can be accessed only by knowing their identifier, without verifying if the user owns this asset or is authorized to access the asset. This allows for users to access other users information without consent and potentially tamper with them depending on the scenario.",
        "validation_criteria": "The endpoint request is flagged when two conditions apply: first, multiple users can access a single endpoint, but each of them uses a unique identifier in the url path when doing so. second, the users can use each others identifiers with this endpoint to get the same responses.",
    },
    AttackClassType.SSRF: {
        "name": "Server-side Request Forgery",
        "acronym": "SSRF",
        "description": "There is a vulnerability in a feature that takes a URL as an input, where a user can input a URL of any destination and get the server to send an HTTP request to it. SSRF vulnerabilities can be utilized to explore your internal network or to carry out denial-of-service attacks against third parties while concealing the attacker's identity.",
        "validation_criteria": "The endpoint is flagged when an outbound detection server that the tool controls, successfully recieves an HTTP request after the tool modifies a URL input in some application feature. The request contains a unique identifier placed by the tool to detect where the request originated from.",
    },
    AttackClassType.JWT: { 
        "name": "Flawed JWT Signature Verification",
        "acronym": "None algorithm",
        "description": "There is a vulnerability in the JWT signauture verification logic where the application accepts different algorithm values for the \"alg\" parameter in the JWT header including insecure values. An example of such values is the \"None\" algoritm, where the client can drop the JWT signature from the token all together and the application will skip token verification. This allows forgery of JWT tokens and can cause catastrophic access control issues.",
        "validation_criteria": "The endpoint request is flagged when the endpoint responds with the original success response even when the JWT was tampered with.",
    },
}
