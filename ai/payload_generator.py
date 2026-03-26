# ai/payload_generator.py

import random

def mutate_payload(payload):
    mutations = [
        payload.upper(),
        payload.lower(),
        payload.replace(" ", "/**/"),
        payload.replace("=", " LIKE "),
        payload.replace("'", "\""),
        payload + "--",
        payload + "#",
    ]
    return random.choice(mutations)


def generate_payloads(base_payloads):

    new_payloads = []

    for payload in base_payloads:
        new_payloads.append(payload)
        for _ in range(3):  # generate variations
            new_payloads.append(mutate_payload(payload))

    return list(set(new_payloads))