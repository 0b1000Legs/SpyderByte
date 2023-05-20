from .AttackClassType import AttackClassType

ATTACK_CLASS_DETAILS = {
    AttackClassType.IDOR: {
        "name": "Insecure Direct Object References",
        "acronym": "IDOR",
        "description": "Commodo excepteur sint dolore sunt. Aliquip exercitation aute nisi tempor laboris laboris aliqua Lorem mollit id qui. Veniam velit consectetur pariatur nostrud aliqua aliquip magna. Ullamco aute qui proident amet eiusmod labore. Laborum veniam cillum consectetur veniam exercitation. Fugiat anim enim do non mollit cupidatat aute ut esse in pariatur. Commodo non amet ea id.",
    },
    AttackClassType.SSRF: {
        "name": "Server-side Request Forgery",
        "acronym": "SSRF",
        "description": "Mollit et dolore officia elit occaecat proident adipisicing. Officia elit irure ipsum magna esse labore ullamco reprehenderit. Ut nulla magna reprehenderit ut elit voluptate tempor officia nisi proident Lorem. Fugiat excepteur culpa eu id magna do fugiat Lorem ad eu.",
    },
    AttackClassType.JWT: {
        "name": "Flawed JWT Signature Verification",
        "acronym": "FJWTSV",
        "description": "Minim mollit sit nulla dolor dolore est dolor. Ut mollit ex irure commodo sit. Adipisicing incididunt anim deserunt id aute. Id ut sint minim esse incididunt adipisicing duis non irure labore adipisicing aute. Reprehenderit et do ea dolor eiusmod in duis pariatur voluptate irure officia veniam eu commodo.",
    },
}
