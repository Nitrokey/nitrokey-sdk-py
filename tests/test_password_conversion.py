import json
import random
import string
import unittest
from dataclasses import asdict
from typing import List

from nitrokey.nk3.credential_exchange_format import (
    BasicAuth,
    CXFKey,
    CXFPayload,
    Item,
    PasswordRepresentation,
    SecretsAppMetadata,
)
from nitrokey.nk3.secrets_app import (
    Algorithm,
    Kind,
    ListItem,
    ListItemProperties,
    PasswordSafeEntry,
)


def test_equality(item: Item, pr: PasswordRepresentation) -> None:
    list_item = pr.item
    pse = pr.pse
    assert item.title.encode() == list_item.label
    assert item.credentials and item.credentials[0]
    assert isinstance(item.credentials[0], BasicAuth)
    assert item.extensions and item.extensions[0]
    assert isinstance(item.extensions[0], SecretsAppMetadata)

    cred = item.credentials[0]
    ext = item.extensions[0]

    assert cred.username and cred.username.value.encode() == pse.login
    assert cred.password and cred.password.value.encode() == pse.password
    assert ext.metadata.encode() == pse.metadata
    assert isinstance(ext.item.properties, ListItemProperties)

    prop = ext.item.properties
    assert prop.touch_required == list_item.properties.touch_required
    assert prop.secret_encryption == list_item.properties.secret_encryption
    assert prop.pws_data_exist == list_item.properties.pws_data_exist


def test_list_equality(item_list: List[Item], pr_list: List[PasswordRepresentation]) -> None:
    assert len(item_list) == len(pr_list)
    for i in range(len(item_list)):
        test_equality(item_list[i], pr_list[i])
        # print("Success")


def generate_test_cases(n: int = 3) -> List[PasswordRepresentation]:
    pr_list = []
    length = 10
    for _ in range(n):
        label = "".join(random.choice(string.ascii_letters) for _ in range(length))
        username = "".join(random.choice(string.ascii_letters) for _ in range(length))
        password = "".join(
            random.choice(string.ascii_letters + string.digits) for _ in range(length)
        )
        prop = random.randrange(0, 8)
        metadata = "".join(random.choice(string.ascii_letters) for _ in range(length))

        list_item = ListItem(
            kind=Kind.NotSet,
            algorithm=Algorithm.Sha1,
            label=label.encode(),
            properties=ListItemProperties.from_byte(prop),
        )

        pse = PasswordSafeEntry(
            login=username.encode(), password=password.encode(), metadata=metadata.encode()
        )

        pr = PasswordRepresentation(list_item, pse)

        pr_list.append(pr)

    return pr_list


def list_convert_pr_to_item(pr_list: List[PasswordRepresentation]) -> List[Item]:
    item_list = []
    for pr in pr_list:
        item_list.append(Item.from_password_representation(pr))
    return item_list


def list_convert_item_to_pr(item_list: List[Item]) -> List[PasswordRepresentation]:
    pr_list = []
    for item in item_list:
        pr = item.password_representation()
        pr_list.extend(pr)
    return pr_list


class TestPasswordExport(unittest.TestCase):
    def test_conversions(self) -> None:
        N = 10  # Number of tests

        # Will perform:
        # Keygen
        # PR list 1 --> Item List 1 --> CXF Payload 1 --> CXF Payload Dict 1 --> Encrypted --> CXF Payload Dict 2 --> CXF Payload 2 --> Item List 2 --> PR list 2
        # Will check the following equalities:
        #   PR lists 1 <--> Item List 1
        #   PR lists 1 <--> Item List 2
        #   PR lists 2 <--> Item List 1
        #   PR lists 2 <--> Item List 2

        pr_list_1 = generate_test_cases(N)
        passphrase = CXFKey.generate_passphrase()
        # print("Passphrase test ", passphrase)
        cxfkey = CXFKey.use_passphrase(passphrase)

        item_list_1 = list_convert_pr_to_item(pr_list_1)
        cxf_payload_1 = CXFPayload.from_items(item_list_1)
        cxf_payload_dict_1 = asdict(cxf_payload_1)
        encrypted_cxf = CXFPayload.from_dict(cxf_payload_dict_1).encrypt(cxfkey)
        cxf_payload_dict_2 = asdict(CXFPayload.decrypt(encrypted_cxf, cxfkey))
        cxf_payload_2 = CXFPayload.from_dict(cxf_payload_dict_2)
        item_list_2 = cxf_payload_2.items()
        pr_list_2 = list_convert_item_to_pr(item_list_2)

        test_list_equality(item_list_1, pr_list_1)
        test_list_equality(item_list_2, pr_list_1)
        test_list_equality(item_list_1, pr_list_2)
        test_list_equality(item_list_2, pr_list_2)


knownVector = """
{
    "version": {
        "major": 1,
        "minor": 0
    },
    "exporterRpId": "exporter.example.com",
    "exporterDisplayName": "Exporter app",
    "timestamp": 1705228800,
    "accounts": [
        {
            "id": "DZSXp7iBQY-Fg-OofakQtQ",
            "username": "jane_smith",
            "email": "jane.smith@example.com",
            "fullName": "Jane Smith",
            "items": [
                {
                    "id": "9OF-QjVDQo2Wp2xWPw6ZhA",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "GitHub Login",
                    "subtitle": "Work GitHub account",
                    "scope": {
                        "urls": ["https://github.com"],
                        "androidApps": []
                    },
                    "credentials": [
                        {
                            "type": "basic-auth",
                            "username": {
                                "id": "-eZX0Gw-TzOsBFwt67N7ZA",
                                "fieldType": "string",
                                "value": "johndoe",
                                "label": "Username field"
                            },
                            "password": {
                                "id": "wgu3wTcXSYawrGMWMtaANg",
                                "fieldType": "concealed-string",
                                "value": "securepassword123",
                                "label": "Password field"
                            }
                        },
                        {
                            "type": "totp",
                            "secret": "JBSWY3DPEHPK3PXP",
                            "period": 30,
                            "digits": 6,
                            "issuer": "GitHub",
                            "algorithm": "sha256",
                            "username": "jane.smith@example.com"
                        }
                    ],
                    "tags": ["development", "git", "work"]
                },
                {
                    "id": "akKA3Y0jQRuK7sKplB0Y9w",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "WebAuthn.io",
                    "subtitle": "johndoe",
                    "credentials": [
                        {
                            "type": "passkey",
                            "credentialId": "Y3JlZGVudGlhbElkRXhhbXBsZQ",
                            "rpId": "webauthn.io",
                            "username": "johndoe",
                            "userDisplayName": "John Doe",
                            "userHandle": "cnEzaNHWcYK3coWZjvoaV1Hj9gnI12mKe2dL2HZVFlY",
                            "key": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgARu_0sCt20EpgVxb4Puq3Ga5VVLpuTY75ngvZlyq3X6hRANCAASmdk1xLsK0oOlhxIPp0d1ZuS0sT9nf6BZtSelhqvLBW0fOL33l_bXgsr_STUHjCLn8l6gcRJwe7OQvbQubZ1dY",
                            "fido2Extensions": {
                                "hmacCredentials": {
                                    "algorithm": "hmac-sha256",
                                    "credWithUV": "j3N5T9qLpWz2rYf4vS6lDn1KpQx8E0fRc2a7Bm5nUsw",
                                    "credWithoutUV": "y2R8tL3eWf5qBz0sK4hHn9rVgX7pD1cQm6uTj2aP8Fs"
                                },
                                "credBlob": "eyJ1c2VyTmFtZSI6ICJKb2huIERvZSIsICJ1c2VySWQiOiAiamRvZS0wMDEiLCAiZW1haWwiOiAiamRvZUBleGFtcGxlLmNvbSJ9",
                                "largeBlob": {
                                    "uncompressedSize": 129,
                                    "data": "HYxBCoUwDESvMgcQT-Hqr71ATIMtlKQkkY-3twrDLIb3Zq8tMEMKUfZ7pBR08lNwdDtAEcaN3vXfsuJnVbGZrNhf82PYrl5ma1JTXCGOQkkLaAxETnmBOb53O51GbYwQdslYHw"
                                },
                                "payments": true
                            }
                        }
                    ]
                },
                {
                    "id": "iz0Q6JWoQ_CbDRboCPJ1Tg",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "Visa Credit Card",
                    "subtitle": "Personal Visa card",
                    "credentials": [
                        {
                            "type": "credit-card",
                            "number": {
                                "id": "MTIz",
                                "fieldType": "concealed-string",
                                "value": "4111111111111111",
                                "label": "Card Number"
                            },
                            "fullName": {
                                "fieldType": "string",
                                "value": "John Doe",
                                "label": "Cardholder Name"
                            },
                            "cardType": {
                                "fieldType": "string",
                                "value": "Visa",
                                "label": "Card Type"
                            },
                            "verificationNumber": {
                                "fieldType": "concealed-string",
                                "value": "123",
                                "label": "CVV"
                            },
                            "pin": {
                                "fieldType": "concealed-string",
                                "value": "0000",
                                "label": "PIN"
                            },
                            "expiryDate": {
                                "fieldType": "year-month",
                                "value": "2027-08",
                                "label": "Expiry Date"
                            },
                            "validFrom": {
                                "fieldType": "year-month",
                                "value": "2024-02",
                                "label": "Valid From"
                            }
                        }
                    ],
                    "tags": ["finance", "credit card", "personal"]
                },
                {
                    "id": "2cGy6PNOSQ2cW43NVxjGSg",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "Wifi",
                    "subtitle": "Home Wifi",
                    "credentials": [
                        {
                            "type": "wifi",
                            "ssid": {
                                "fieldType": "string",
                                "value": "Home_Network",
                                "label": "Wi-Fi SSID"
                            },
                            "networkSecurityType": {
                                "fieldType": "wifi-network-security-type",
                                "value": "wpa2-personal",
                                "label": "Security Type"
                            },
                            "passphrase": {
                                "fieldType": "concealed-string",
                                "value": "mypassword123",
                                "label": "Wi-Fi Password"
                            },
                            "hidden": {
                                "fieldType": "boolean",
                                "value": "false",
                                "label": "Hidden Network"
                            }
                        }
                    ]
                },
                {
                    "id": "s4TK1UNTRhG4j1DQawUz8g",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "Home alarm",
                    "subtitle": "instructions",
                    "credentials": [
                        {
                            "type": "note",
                            "content": {
                                "fieldType": "string",
                                "value": "some instructionts to enable/disable the alarm",
                                "label": "alarm"
                            }
                        }
                    ]
                },
                {
                    "id": "BQzS9Ws3RnOabLzFuyOu7Q",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "Driver License",
                    "subtitle": "US",
                    "credentials": [
                        {
                            "type": "drivers-license",
                            "fullName": {
                                "fieldType": "string",
                                "value": "John Doe",
                                "label": "Full Name"
                            },
                            "birthDate": {
                                "fieldType": "date",
                                "value": "1990-05-15",
                                "label": "Date of Birth"
                            },
                            "issueDate": {
                                "fieldType": "date",
                                "value": "2020-06-01",
                                "label": "Issue Date"
                            },
                            "expiryDate": {
                                "fieldType": "date",
                                "value": "2030-06-01",
                                "label": "Expiry Date"
                            },
                            "issuingAuthority": {
                                "fieldType": "string",
                                "value": "Department of Motor Vehicles",
                                "label": "Issuing Authority"
                            },
                            "territory": {
                                "fieldType": "subdivision-code",
                                "value": "US-CA",
                                "label": "Territory"
                            },
                            "country": {
                                "fieldType": "country-code",
                                "value": "US",
                                "label": "Country"
                            },
                            "licenseNumber": {
                                "fieldType": "string",
                                "value": "D12345678",
                                "label": "License Number"
                            },
                            "licenseClass": {
                                "fieldType": "string",
                                "value": "C",
                                "label": "License Class"
                            }
                        }
                    ]
                },
                {
                    "id": "HHl63ybfQG6GBRHlyrvKfg",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "House Address",
                    "subtitle": "US",
                    "credentials": [
                        {
                            "type": "address",
                            "streetAddress": {
                                "fieldType": "string",
                                "value": "123 Main Street",
                                "label": "Street Address"
                            },
                            "postalCode": {
                                "fieldType": "string",
                                "value": "12345",
                                "label": "Postal Code"
                            },
                            "city": {
                                "fieldType": "string",
                                "value": "Springfield",
                                "label": "City"
                            },
                            "territory": {
                                "fieldType": "subdivision-code",
                                "value": "US-CA",
                                "label": "State"
                            },
                            "country": {
                                "fieldType": "country-code",
                                "value": "US",
                                "label": "Country"
                            },
                            "tel": {
                                "fieldType": "string",
                                "value": "+1-555-123-4567",
                                "label": "Telephone"
                            }
                        }
                    ]
                },
                {
                    "id": "Z4cFmc21Q5-vCVwd1wJx1g",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "SSH Key",
                    "subtitle": "GitHub",
                    "credentials": [
                        {
                            "type": "ssh-key",
                            "keyType": "ssh-rsa",
                            "privateKey": "MIIG_QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQCn4-QiJojZ9mgc9KYJIvDWGaz4qFhf0CButg6L8zEoHKwuiN-mqcEciCCOa9BNiJmm8NTTehZvrrglGG59zIbqYtDAHjVn-vtb49xPzIv-M651Yqj08lIbR9tEIHKCq7aH8GlDm8NgG9EzJGjlL7okQym4TH1MHl-s4mUyr_qb2unlZBDixAQsphU8iCLftukWCIkmQg4CSj1Gh3WbBlZ-EX5eW0EXuAw4XsSbBTWV9CHRowVIpYqPvEYSpHsoCjEcd988p19hpiGknA0J4z7JfUlNgyT_1chb8GCTDT-2DCBRApbsIg6TOBVS-PR6emAQ3eZzUW0-3_oRM4ip0ujltQy8uU6gvYIAqx5wXGMThVpZcUgahKiSsVo_s4b84iMe4DG3W8jz4qi6yyNv0VedEzPUZ1lXd1GJFoy9uKNuSTe-1ksicAcluZN6LuNsPHcPxFCzOcmoNnVXEKAXInt-ys__5CDVasroZSAHZnDjUD4oNsLI3VIOnGxgXrkwSH0CAwEAAQKCAYAA2SDMf7OBHw1OGM9OQa1ZS4u-ktfQHhn31-FxbrhWGp-lDt8gYABVf6Y4dKN6rMtn7D9gVSAlZCAn3Hx8aWAvcXHaspxe9YXiZDTh-Kd8EIXxBQn-TiDA5LH0dryABqmMp20vYKtR7OS3lIIXfFBSrBMwdunKzLwmKwZLWq0SWf6vVbwpxRyR9CyByodF6DjmZK3QB2qQ3jqlL1HWXL0VnyArY7HLvUvfLLK4vMPqnsSH-FdHvhcEhwqMlWT44g-fhqWtCJNnjDgLK3FPbI8Pz9TF8dWJvOmp5Q6iSBua1e9x2LizVuNSqiFc7ZTLeoG4nDj7T2BtqB0E1rNUDEN1aBo-UZmHJK7LrzfW_B-ssi2WwIpfxYa1lO6HFod5_YQiXV1GunyH1chCsbvOFtXvAHASO4HTKlJNbWhRF1GXqnKpAaHDPCVuwp3eq6Yf0oLbXrL3KFZ3jwWiWbpQXRVvpqzaJwZn3CN1yQgYS9j17a9wrPky-BoJxXjZ_oImWLECgcEA0lkLwiHvmTYFTCC7PN938Agk9_NQs5PQ18MRn9OJmyfSpYqf_gNp-Md7xUgtF_MTif7uelp2J7DYf6fj9EYf9g4EuW-SQgFP4pfiJn1-zGFeTQq1ISvwjsA4E8ZSt-GIumjZTg6YiL1_A79u4wm24swt7iqnVViOPtPGOM34S1tAamjZzq2eZDmAF6pAfmuTMdinCMR1E1kNJYbxeqLiqQCXuwBBnHOOOJofN3AkvzjRUBB9udvniqYxH3PQcxPxAoHBAMxT5KwBhZhnJedYN87Kkcpl7xdMkpU8b-aXeZoNykCeoC-wgIQexnSWmFk4HPkCNxvCWlbkOT1MHrTAKFnaOww23Ob-Vi6A9n0rozo9vtoJig114GB0gUqEmtfLhO1P5AE8yzogE-ILHyp0BqXt8vGIfzpDnCkN-GKl8gOOMPrR4NAcLO-Rshc5nLs7BGB4SEi126Y6mSfp85m0--1QhWMz9HzqJEHCWKVcZYdCdEONP9js04EUnK33KtlJIWzZTQKBwAT0pBpGwmZRp35Lpx2gBitZhcVxrg0NBnaO2fNyAGPvZD8SLQLHAdAiov_a23Uc_PDbWLL5Pp9gwzj-s5glrssVOXdE8aUscr1b5rARdNNL1_Tos6u8ZUZ3sNqGaZx7a8U4gyYboexWyo9EC1C-AdkGBm7-AkM4euFwC9N6xsa_t5zKK5d676hc0m-8SxivYCBkgkrqlfeGuZCQxU-mVsC0it6U-va8ojUjLGkZ80OuCwBf4xZl3-acU7vx9o8_gQKBwB7BrhU6MWrsc-cr_1KQaXum9mNyckomi82RFYvb8Yrilcg38FBy9XqNRKeBa9MLw1HZYpHbzsXsVF7u4eQMloDTLVNUC5L6dKAI1owoyTa24uH90WWTg_a8mTZMe1jhgrew-AJq27NV6z4PswR9GenDmyshDDudz7rBsflZCQRoXUfWRelV7BHU6UPBsXn4ASF4xnRyM6WvcKy9coKZcUqqgm3fLM_9OizCCMJgfXHBrE-x7nBqst746qlEedSRrQKBwQCVYwwKCHNlZxl0_NMkDJ-hp7_InHF6mz_3VO58iCb19TLDVUC2dDGPXNYwWTT9PclefwV5HNBHcAfTzgB4dpQyNiDyV914HL7DFEGduoPnwBYjeFre54v0YjjnskjJO7myircdbdX__i-7LMUw5aZZXCC8a5BD_rdV6IKJWJG5QBXbe5fVf1XwOjBTzlhIPIqhNFfSu-mFikp5BRwHGBqsKMju6inYmW6YADeY_SvOQjDEB37RqGZxqyIx8V2ZYwU",
                            "keyComment": "Work SSH Key",
                            "creationDate": {
                                "fieldType": "date",
                                "value": "2023-01-01",
                                "label": "Creation Date"
                            },
                            "expiryDate": {
                                "fieldType": "date",
                                "value": "2025-01-01",
                                "label": "Expiry Date"
                            },
                            "keyGenerationSource": {
                                "fieldType": "string",
                                "value": "Generated using OpenSSH",
                                "label": "Key Generation Source"
                            }
                        }
                    ]
                },
                {
                    "id": "EWM-4m3pSEi0ZBQbFVB92g",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "ID card",
                    "subtitle": "US",
                    "credentials": [
                        {
                            "type": "file",
                            "id": "VGVzdEZpbGVJRA",
                            "name": "example-file.txt",
                            "decryptedSize": 21,
                            "integrityHash": "crWLSYO8T2f3yGaHQlDrMVvSvuu1YdXZewkjps422lQ"
                        }
                    ]
                },
                {
                    "id": "U9TPhd80SsWKKUtx3HxVsA",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "ID card",
                    "subtitle": "US",
                    "credentials": [
                        {
                            "type": "identity-document",
                            "issuingCountry": {
                                "fieldType": "country-code",
                                "value": "US",
                                "label": "Issuing Country"
                            },
                            "documentNumber": {
                                "fieldType": "string",
                                "value": "123456789",
                                "label": "Document Number"
                            },
                            "identificationNumber": {
                                "fieldType": "string",
                                "value": "ID123456789",
                                "label": "Identification Number"
                            },
                            "nationality": {
                                "fieldType": "string",
                                "value": "American",
                                "label": "Nationality"
                            },
                            "fullName": {
                                "fieldType": "string",
                                "value": "Jane Doe",
                                "label": "Full Name"
                            },
                            "birthDate": {
                                "fieldType": "date",
                                "value": "1990-04-15",
                                "label": "Birth Date"
                            },
                            "birthPlace": {
                                "fieldType": "string",
                                "value": "New York, USA",
                                "label": "Birth Place"
                            },
                            "sex": {
                                "fieldType": "string",
                                "value": "F",
                                "label": "Sex"
                            },
                            "issueDate": {
                                "fieldType": "date",
                                "value": "2020-01-01",
                                "label": "Issue Date"
                            },
                            "expiryDate": {
                                "fieldType": "date",
                                "value": "2030-01-01",
                                "label": "Expiry Date"
                            },
                            "issuingAuthority": {
                                "fieldType": "string",
                                "value": "Department of State",
                                "label": "Issuing Authority"
                            }
                        }
                    ]
                },
                {
                    "id": "K4BBlNWWTS21ZqzTUn0H6Q",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "Passport",
                    "subtitle": "US",
                    "credentials": [
                        {
                            "type": "passport",
                            "issuingCountry": {
                                "fieldType": "country-code",
                                "value": "US",
                                "label": "Issuing Country"
                            },
                            "passportType": {
                                "fieldType": "string",
                                "value": "PP",
                                "label": "Passport Type"
                            },
                            "passportNumber": {
                                "fieldType": "string",
                                "value": "A12345678",
                                "label": "Passport Number"
                            },
                            "nationalIdentificationNumber": {
                                "fieldType": "string",
                                "value": "ID123456789",
                                "label": "National Identification Number"
                            },
                            "nationality": {
                                "fieldType": "string",
                                "value": "American",
                                "label": "Nationality"
                            },
                            "fullName": {
                                "fieldType": "string",
                                "value": "John Doe",
                                "label": "Full Name"
                            },
                            "birthDate": {
                                "fieldType": "date",
                                "value": "1990-01-01",
                                "label": "Birth Date"
                            },
                            "birthPlace": {
                                "fieldType": "string",
                                "value": "Los Angeles, USA",
                                "label": "Birth Place"
                            },
                            "sex": {
                                "fieldType": "string",
                                "value": "M",
                                "label": "Sex"
                            },
                            "issueDate": {
                                "fieldType": "date",
                                "value": "2015-06-15",
                                "label": "Issue Date"
                            },
                            "expiryDate": {
                                "fieldType": "date",
                                "value": "2025-06-15",
                                "label": "Expiry Date"
                            },
                            "issuingAuthority": {
                                "fieldType": "string",
                                "value": "U.S. Department of State",
                                "label": "Issuing Authority"
                            }
                        }
                    ]
                },
                {
                    "id": "LmInpZjdRwKIKZFdbBz19g",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "John Doe",
                    "subtitle": "personal name",
                    "credentials": [
                        {
                            "type": "person-name",
                            "title": {
                                "fieldType": "string",
                                "value": "Dr.",
                                "label": "Title"
                            },
                            "given": {
                                "fieldType": "string",
                                "value": "John",
                                "label": "Given Name"
                            },
                            "givenInformal": {
                                "fieldType": "string",
                                "value": "Johnny",
                                "label": "Informal Given Name"
                            },
                            "given2": {
                                "fieldType": "string",
                                "value": "Michael",
                                "label": "Second Given Name"
                            },
                            "surnamePrefix": {
                                "fieldType": "string",
                                "value": "van",
                                "label": "Surname Prefix"
                            },
                            "surname": {
                                "fieldType": "string",
                                "value": "Doe",
                                "label": "Surname"
                            },
                            "surname2": {
                                "fieldType": "string",
                                "value": "Smith",
                                "label": "Second Surname"
                            },
                            "credentials": {
                                "fieldType": "string",
                                "value": "PhD",
                                "label": "Credentials"
                            },
                            "generation": {
                                "fieldType": "string",
                                "value": "III",
                                "label": "Generation"
                            }
                        }
                    ]
                },
                {
                    "id": "TMrjj3uIRtitVmIpiwXmyg",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "API key",
                    "subtitle": "john_doe",
                    "credentials": [
                        {
                            "type": "api-key",
                            "key": {
                                "fieldType": "concealed-string",
                                "value": "AIzaSyAyRofL-VJHZofHc-qOSkqVOdhvgQoJADk",
                                "label": "API Key"
                            },
                            "username": {
                                "fieldType": "string",
                                "value": "john_doe",
                                "label": "Username"
                            },
                            "keyType": {
                                "fieldType": "string",
                                "value": "Bearer",
                                "label": "Key Type"
                            },
                            "url": {
                                "fieldType": "string",
                                "value": "https://api.example.com",
                                "label": "API URL"
                            },
                            "validFrom": {
                                "fieldType": "date",
                                "value": "2025-01-01",
                                "label": "Valid From"
                            },
                            "expiryDate": {
                                "fieldType": "date",
                                "value": "2026-01-01",
                                "label": "Expiry Date"
                            }
                        }
                    ]
                },
                {
                    "id": "QtvgfXSgS8O6ukLNZZKMlw",
                    "creationAt": 1705142400,
                    "modifiedAt": 1705228800,
                    "title": "Generated Password",
                    "subtitle": "john_doe",
                    "credentials": [
                        {
                            "type": "generated-password",
                            "password": "KozyS!cf#Nc9C799"
                        }
                    ]
                }
            ],
            "collections": [
                {
                    "id": "0dimBl7dRRyPLGKGxEEm5Q",
                    "creationAt": 1705228800,
                    "modifiedAt": 1705228800,
                    "title": "Work Accounts",
                    "subtitle": "A collection of pro accounts for various services",
                    "items": [
                        {
                            "item": "TMrjj3uIRtitVmIpiwXmyg",
                            "account": "DZSXp7iBQY-Fg-OofakQtQ"
                        },
                        {
                            "item": "Z4cFmc21Q5-vCVwd1wJx1g",
                            "account": "DZSXp7iBQY-Fg-OofakQtQ"
                        },
                        {
                            "item": "9OF-QjVDQo2Wp2xWPw6ZhA",
                            "account": "DZSXp7iBQY-Fg-OofakQtQ"
                        }
                    ]
                }
            ]
        }
    ]
}
"""


class TestKnownVector(unittest.TestCase):
    def test_knownvector(self) -> None:
        cxfpayload = CXFPayload.from_dict(json.loads(knownVector))
        items = cxfpayload.items()
        pr_list = []
        for item in items:
            pr_list.extend(item.password_representation())
        assert len(pr_list) == 1  # Only one basic auth cred
        pr = pr_list[0]
        list_item = pr.item
        pse = pr.pse

        assert pse.login == b"johndoe"
        assert pse.password == b"securepassword123"

        assert (
            list_item.properties.secret_encryption
        )  # Fail safe to pin protect if nothing mentioned in the CXF
        assert (
            list_item.properties.touch_required
        )  # Fail safe to use touch if nothing mentioned in the CXF


if __name__ == "__main__":
    TestPasswordExport().test_conversions()
