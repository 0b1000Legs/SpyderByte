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
        "description": "",
        "validation_criteria": "s",
    },
    AttackClassType.JWT: { 
        "name": "Flawed JWT Signature Verification",
        "acronym": "None algorithm",
        "description": "There is a vulnerability in the JWT signauture verification logic where the application accepts different algorithm values for the \"alg\" parameter in the JWT header including insecure values. An example of such values is the \"None\" algoritm, where the client can drop the JWT signature from the token all together and the application will skip token verification. This allows forgery of JWT tokens and can cause catastrophic access control issues.",
        "validation_criteria": "The endpoint request is flagged when the endpoint responds with the original success response even when the JWT was tampered with.",
    },
}
